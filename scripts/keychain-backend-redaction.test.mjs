import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('production Keychain startup errors discard raw backend diagnostics (#109)', async () => {
  const source = await readFile('src-tauri/src/secrets.rs', 'utf8');
  assert.match(source, /fn redacted_keychain_failure\(kind: KeychainFailureKind\) -> String/);
  assert.match(source, /\.map_err\(\|_\| redacted_keychain_failure\(KeychainFailureKind::Entry\)\)/);
  assert.match(source, /Err\(_\) => return Err\(redacted_keychain_failure\(KeychainFailureKind::Read\)\)/);
  assert.match(source, /\.map_err\(\|_\| redacted_keychain_failure\(KeychainFailureKind::Write\)\)/);
  assert.match(source, /Err\(keyring::Error::NoEntry\) => \{\}/);
  assert.match(source, /OsRng\.fill_bytes\(&mut entropy\)/);
  assert.match(source, /Refusing a short existing API token in Keychain/);
  assert.match(source, /fn keychain_backend_failure_messages_are_fixed_and_secret_free/);
  assert.doesNotMatch(source, /Keychain (unavailable|read failed|write failed): \{/);
});
