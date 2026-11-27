import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('Ask never silently truncates a tool preview before approval', async () => {
  const gate = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const ask = gate.indexOf('Policy::Ask => {');
  const limit = gate.indexOf('preview.len() > MAX_APPROVAL_PREVIEW_BYTES', ask);
  const preview = gate.indexOf('preview: preview.to_owned()', limit);
  const insert = gate.indexOf('pending.entries.insert(', preview);
  const emit = gate.indexOf('self.events.send(request)', insert);
  assert.ok(ask > 0 && limit > ask && preview > limit && insert > preview && emit > insert);
  assert.doesNotMatch(gate, /preview\.chars\(\)\.take\(/);
  assert.match(registry, /std::ascii::escape_default\(byte\)/);
  assert.match(registry, /escaped_preview\(input\.command\.as_bytes\(\)\)/);
  assert.match(registry, /escaped_preview\(directory\.as_os_str\(\)\.as_encoded_bytes\(\)\)/);
  assert.match(registry, /escaped_preview\(path\.as_os_str\(\)\.as_encoded_bytes\(\)\)/);
});

test('trusted approval preview is literal text with whitespace preserved', async () => {
  const html = await readFile('webview/index.html', 'utf8');
  const css = await readFile('webview/app.css', 'utf8');
  const app = await readFile('webview/pages/approval-inbox.ts', 'utf8');
  assert.match(html, /<pre id="approval-text">/);
  assert.match(css, /#approval-text\{[^}]*max-height:none[^}]*white-space:pre-wrap/);
  assert.match(app, /preview\.textContent = current\s*\? current\.tool \+ ': ' \+ current\.preview/);
  assert.doesNotMatch(app, /preview\.innerHTML/);
});
