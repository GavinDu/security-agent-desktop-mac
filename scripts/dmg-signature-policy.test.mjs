import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

function accepted(details) {
  const command = [
    'source scripts/dmg-signature-policy.sh',
    'require_exact_adhoc_signature_details "$1"',
  ].join('\n');
  const result = spawnSync('/bin/bash', ['-c', command, 'test-signature', details], {
    encoding: 'utf8',
    timeout: 2000,
  });
  assert.equal(result.error, undefined);
  return result.status === 0;
}

test('only standalone ad-hoc signature line is accepted on developer DMG (#119)', () => {
  assert.equal(accepted('Identifier=test\nSignature=adhoc\nFormat=app bundle'), true);
  assert.equal(accepted('Signature=adhoc'), true);
  for (const value of [
    '', 'code object is not signed at all',
    'Signature=Developer ID Application: Example',
    'Signature=adhoc-forged',
    'Other line Signature=adhoc',
    'Signature=adhoc extra suffix',
    'Signature=adhoc\r',
  ]) assert.equal(accepted(value), false, 'unexpectedly accepted ' + value);
});

test('mounted verifier requires strict ad-hoc seal, not unsigned fallback (#119)', async () => {
  const verifier = await readFile('scripts/verify-macos-bundle.sh', 'utf8');
  assert.match(verifier, /dmg-signature-policy\.sh/);
  assert.match(verifier, /if ! signature_details=\$\(\/usr\/bin\/codesign --display --verbose=2 "\$app" 2>&1\)/);
  assert.match(verifier, /if ! require_exact_adhoc_signature_details "\$signature_details"/);
  assert.match(verifier, /\/usr\/bin\/codesign --verify --strict "\$app"/);
  assert.match(verifier, /if ! \/usr\/bin\/codesign --display --entitlements :- "\$app"/);
  assert.match(verifier, /require_single_inventory_path "\$dmg_dir" '\*\.dmg' file/);
  assert.match(verifier, /require_single_inventory_path "\$mount_dir" '\*\.app' directory/);
  assert.doesNotMatch(verifier, /code object is not signed at all/);
  assert.doesNotMatch(verifier, /Code-signature check: unsigned,/);
});
