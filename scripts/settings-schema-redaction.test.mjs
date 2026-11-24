import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('settings schema errors never include untrusted parser text (#199)', async () => {
  const code = await readFile('src-tauri/src/settings.rs', 'utf8');
  const read = code.slice(code.indexOf('fn load_at('), code.indexOf('pub fn save('));
  assert.match(read, /serde_json::from_slice\(&bytes\)\.map_err\(\|_\| "Invalid settings\.json"\.to_owned\(\)\)/);
  assert.doesNotMatch(read, /format!\("Invalid settings\.json:/);
  assert.match(code, /fn invalid_settings_json_diagnostics_never_echo_untrusted_field_names\(/);
  assert.match(code, /SECRET_TOKEN_MARKER/);
  assert.match(code, /assert_eq!\(failure, "Invalid settings\.json"\)/);
  assert.match(code, /assert!\(!failure\.contains\("SECRET_TOKEN_MARKER"\)\)/);
});

test('settings trust boundary remains fail closed and bounded (#199)', async () => {
  const code = await readFile('src-tauri/src/settings.rs', 'utf8');
  const read = code.slice(code.indexOf('fn load_at('), code.indexOf('pub fn save('));
  for (const gate of [
    'checked_settings_directory(parent)',
    'libc::O_NOFOLLOW',
    'libc::O_NONBLOCK',
    'metadata.nlink() != 1',
    'metadata.len() > MAX_SETTINGS_BYTES',
    'file.take(MAX_SETTINGS_BYTES + 1)',
  ]) assert.ok(read.includes(gate), gate);
  assert.match(code, /#\[serde\(default, deny_unknown_fields\)\]/);
});
