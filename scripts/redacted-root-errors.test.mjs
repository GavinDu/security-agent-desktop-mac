import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('root-grant and file-path denials never interpolate caller paths or OS errors (#98)', async () => {
  const source = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(source, /"Invalid granted root"/);
  assert.match(source, /"Granted root is not a directory"/);
  assert.match(source, /"Requested file path is inaccessible"/);
  assert.match(source, /fn file_authorization_errors_do_not_echo_private_paths/);
  assert.doesNotMatch(source, /format!\("Invalid root: \{root\}"\)/);
  assert.doesNotMatch(source, /format!\("Not a directory: \{root\}"\)/);
  assert.doesNotMatch(source, /format!\("Path not accessible: \{e\}"\)/);
});
