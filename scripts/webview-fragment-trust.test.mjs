import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('privileged bundled URL requires no query, fragment or alternate origin (#131)', async () => {
  const source = await readFile('src-tauri/src/navigation.rs', 'utf8');
  assert.match(source, /url\.scheme\(\) == "tauri"/);
  assert.match(source, /url\.host_str\(\) == Some\("localhost"\)/);
  assert.match(source, /url\.port\(\)\.is_none\(\)/);
  assert.match(source, /url\.username\(\)\.is_empty\(\)/);
  assert.match(source, /url\.password\(\)\.is_none\(\)/);
  assert.match(source, /url\.query\(\)\.is_none\(\)/);
  assert.match(source, /url\.fragment\(\)\.is_none\(\)/);
  assert.match(source, /matches!\(url\.path\(\), "\/" \| "\/index\.html"\)/);
  for (const hostile of [
    'tauri://localhost/#route',
    'tauri://localhost/index.html#untrusted-command',
    'tauri://localhost/index.html#%2Fsettings',
    'tauri://localhost/index.html#',
  ]) {
    assert.ok(source.includes('"' + hostile + '"'), hostile + ' needs Rust regression coverage');
  }
});

test('trusted-main WebView keeps native nav/popup and sender-auth boundary (#131)', async () => {
  const source = await readFile('src-tauri/src/app.rs', 'utf8');
  const guard = await readFile('src-tauri/src/navigation.rs', 'utf8');
  const start = source.indexOf('WebviewWindowBuilder::from_config(app, &window_config)');
  const nav = source.indexOf('.on_navigation(navigation::trusted_main_document)', start);
  const popup = source.indexOf('.on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)', nav);
  const build = source.indexOf('.build()?', popup);
  assert.ok(start > 0 && nav > start && popup > nav && build > popup);
  assert.match(guard, /if !trusted_main_document\(&current\)/);
  assert.match(guard, /window\.label\(\) != "main"/);
});
