import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('root-grant and file-path denials never interpolate caller paths or OS errors (#98/#115)', async () => {
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const pinned = await readFile('src-tauri/src/tools/pinned_read.rs', 'utf8');
  assert.match(pinned, /"Invalid granted root"/);
  assert.match(pinned, /"Granted root is not a directory"/);
  assert.match(registry, /"Requested file path is inaccessible"/);
  assert.match(registry, /fn file_authorization_errors_do_not_echo_private_paths/);
  assert.match(pinned, /fn pin_absolute_directory/);
  assert.match(pinned, /libc::openat/);
  assert.doesNotMatch(registry, /format!\("Path not accessible: \{e\}"\)/);
  assert.doesNotMatch(registry, /format!\("Invalid root: \{root\}"\)/);
  assert.doesNotMatch(pinned, /format!\("Invalid root: \{root\}"\)/);
});
