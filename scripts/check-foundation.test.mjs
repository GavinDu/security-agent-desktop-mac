import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const config = await json('src-tauri/tauri.conf.json');
const capability = await json('src-tauri/capabilities/default.json');

test('the only configured privileged desktop WebView must be created with navigation guards', () => {
  assert.equal(config.app.windows.length, 1);
  assert.equal(config.app.windows[0].label, 'main');
  assert.equal(config.app.windows[0].create, false);
  assert.equal(config.app.withGlobalTauri, false);
  assert.equal(config.identifier, 'com.gavindu.securityagent.desktop');
});

test('CSP prevents remote JS, frames, forms and active third-party resources', () => {
  const csp = config.app.security.csp;
  for (const directive of [
    "default-src 'self'", "script-src 'self'", "style-src 'self'",
    "object-src 'none'", "base-uri 'none'", "frame-src 'none'",
    "form-action 'none'", "worker-src 'none'", "media-src 'none'",
  ]) assert.ok(csp.includes(directive), directive);
  assert.ok(!csp.includes('https:'), 'do not open generic HTTPS script access');
});

test('main window is sole ACL receiver and event listeners are the only core grants', () => {
  assert.deepEqual(capability.windows, ['main']);
  assert.ok(!('remote' in capability), 'never enable remote origins');
  assert.deepEqual(
    [...capability.permissions].sort(),
    ['core:event:allow-listen', 'core:event:allow-unlisten'].sort()
  );
});

test('WebView distribution is entirely locally bundled', async () => {
  const html = await readFile('src-tauri/dist/index.html', 'utf8');
  const script = await readFile('src-tauri/dist/app.js', 'utf8');
  const stylesheet = await readFile('src-tauri/dist/app.css', 'utf8');
  assert.match(html, /<script src="app\.js" defer><\/script>/);
  assert.match(html, /href="app\.css"/);
  assert.ok(script.length > 100);
  assert.ok(stylesheet.length > 100);
  assert.doesNotMatch(html, /<iframe\b|<form\b|https?:\/\//i);
});
