import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Source-level regression: the actual Tauri WebView TypeScript is compiled
// by the separate frontend typecheck, not evaluated by a Node DOM shim.
const source = await readFile('webview/pages/app.ts', 'utf8');
const roots = source.slice(source.indexOf('async function updateRoots('), source.indexOf("el('refresh').addEventListener"));
const peer = source.slice(source.indexOf("el('previewPeer').addEventListener"), source.indexOf("allow.addEventListener('click'"));

test('root grant failures use fixed text, never render raw rejected IPC details (#152)', () => {
  assert.match(roots, /await connectorBridge\.setAllowedRoots\(roots\)/);
  assert.match(roots, /catch \{[\s\S]*?Directory permissions were not changed\./);
  assert.doesNotMatch(roots, /String\s*\(\s*error\s*\)|JSON\.stringify\s*\(\s*error\s*\)|console\./);
  assert.match(roots, /el\('settingsNotice'\)\.textContent/);
  assert.match(roots, /await refresh\(\)/);
});

test('peer preview failure is static and stale response/rejection cannot overwrite latest request (#152)', () => {
  assert.match(source, /let peerPreviewEpoch = 0/);
  assert.match(peer, /const epoch = \+\+peerPreviewEpoch/);
  assert.match(peer, /connectorBridge\.previewWireGuardPeer\(publicKey, tunnelIp\)/);
  assert.match(peer, /\.then\(\(config\) => \{\s*if \(epoch === peerPreviewEpoch\) el\('peerPreview'\)\.textContent = config/);
  assert.match(peer, /\.catch\(\(\) => \{\s*if \(epoch === peerPreviewEpoch\) \{/);
  assert.match(peer, /Peer preview unavailable\. Check the public key and tunnel address\./);
  assert.doesNotMatch(peer, /String\s*\(\s*error\s*\)|JSON\.stringify\s*\(\s*error\s*\)|console\./);
  assert.match(peer, /el\('peerPreview'\)\.textContent/);
  assert.doesNotMatch(peer, /innerHTML|outerHTML|insertAdjacentHTML/);
});

test('no arbitrary Tauri failures are echoed to these trusted UI surfaces (#152)', () => {
  for (const handler of [roots, peer]) {
    assert.doesNotMatch(handler, /catch\s*\(\s*error/);
    assert.doesNotMatch(handler, /\+\s*(?:String\(error\)|error)(?:\b|\))/);
  }
});
