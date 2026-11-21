import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Source-level regression: the actual Tauri WebView TypeScript is compiled
// by the separate frontend typecheck, not evaluated by a Node DOM shim.
const source = await readFile('webview/pages/app.ts', 'utf8');
const roots = source.slice(source.indexOf('async function updateRoots('), source.indexOf("el('refresh').addEventListener"));
const peer = source.slice(source.indexOf("el('previewPeer').addEventListener"), source.indexOf("allow.addEventListener('click'"));

test('root grant failures use fixed text, never render raw rejected IPC details (#152)', () => {
  // Root writes now pass through the already-merged #154 single-flight coordinator.
  assert.match(roots, /await rootWrites\.tryWrite\(roots,/);
  assert.match(roots, /connectorBridge\.setAllowedRoots\(nextRoots\)/);
  assert.match(roots, /catch \{[\s\S]*?Directory permission update was not acknowledged\./);
  assert.doesNotMatch(roots, /String\s*\(\s*error\s*\)|JSON\.stringify\s*\(\s*error\s*\)|console\./);
  assert.match(roots, /el\('settingsNotice'\)\.textContent/);
  assert.match(roots, /await refresh\(\)/);
});

test('peer preview failure is static and stale response/rejection cannot overwrite latest request (#152)', () => {
  assert.match(source, /let peerPreviewEpoch = 0/);
  assert.match(peer, /const epoch = \+\+peerPreviewEpoch/);
  assert.match(peer, /connectorBridge\.previewWireGuardPeer\(publicKey, tunnelIp\)/);
  assert.match(peer, /const current = \(\) => epoch === peerPreviewEpoch &&/);
  assert.match(peer, /peerKeyInput\.value\.trim\(\) === publicKey &&/);
  assert.match(peer, /peerIpInput\.value\.trim\(\) === tunnelIp/);
  assert.match(peer, /\.then\(\(config\) => \{\s*if \(current\(\)\) peerPreview\.textContent = config/);
  assert.match(peer, /\.catch\(\(\) => \{\s*if \(current\(\)\) \{/);
  assert.match(peer, /Peer preview unavailable\. Check the public key and tunnel address\./);
  assert.doesNotMatch(peer, /String\s*\(\s*error\s*\)|JSON\.stringify\s*\(\s*error\s*\)|console\./);
  assert.match(peer, /peerPreview\.textContent/);
  assert.doesNotMatch(peer, /innerHTML|outerHTML|insertAdjacentHTML/);
});

test('changing either peer input invalidates pending and displayed previews (#152)', () => {
  const invalidation = source.slice(
    source.indexOf('function invalidatePeerPreview()'),
    source.indexOf("el('previewPeer').addEventListener"),
  );
  assert.match(invalidation, /peerPreviewEpoch \+= 1/);
  assert.match(invalidation, /peerPreview\.textContent = 'Peer preview cleared\./);
  assert.match(invalidation, /peerKeyInput\.addEventListener\('input', invalidatePeerPreview\)/);
  assert.match(invalidation, /peerIpInput\.addEventListener\('input', invalidatePeerPreview\)/);
  assert.match(peer, /peerKeyInput\.value\.trim\(\) === publicKey/);
  assert.match(peer, /peerIpInput\.value\.trim\(\) === tunnelIp/);
});

test('no arbitrary Tauri failures are echoed to these trusted UI surfaces (#152)', () => {
  for (const handler of [roots, peer]) {
    assert.doesNotMatch(handler, /catch\s*\(\s*error/);
    assert.doesNotMatch(handler, /\+\s*(?:String\(error\)|error)(?:\b|\))/);
  }
});
