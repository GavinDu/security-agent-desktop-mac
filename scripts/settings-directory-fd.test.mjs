import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('settings load and save are pinned to owned nofollow directory descriptor (#137)', async () => {
  const code = await readFile('src-tauri/src/settings.rs', 'utf8');
  assert.match(code, /fn checked_settings_directory\(path: &Path\)/);
  assert.match(code, /libc::O_DIRECTORY \| libc::O_NOFOLLOW \| libc::O_CLOEXEC/);
  assert.match(code, /metadata\.uid\(\) != unsafe \{ libc::geteuid\(\) \}/);
  assert.match(code, /metadata\.mode\(\) & 0o022 != 0/);
  assert.match(code, /fn open_settings_at\(/);
  assert.match(code, /libc::openat\(\s*directory\.as_raw_fd\(\),\s*leaf\.as_ptr\(\),\s*flags,\s*mode as libc::c_uint,\s*\)/);

  const load = code.slice(code.indexOf('fn load_at('), code.indexOf('pub fn save('));
  assert.match(load, /checked_settings_directory\(parent\)/);
  assert.match(load, /libc::O_RDONLY \| libc::O_NOFOLLOW \| libc::O_CLOEXEC \| libc::O_NONBLOCK/);
  assert.match(load, /metadata\.nlink\(\) != 1/);

  const save = code.slice(code.indexOf('fn save_at('), code.indexOf('#\[cfg\(test\)\]'));
  assert.match(save, /checked_settings_directory\(parent\)/);
  assert.match(save, /libc::O_EXCL/);
  assert.match(save, /libc::renameat\(/);
  assert.match(save, /libc::unlinkat\(/);
  assert.match(save, /file\.sync_all\(\)/);
});

test('native regression covers unsafe final parent, FD swap and old leaf guards (#137)', async () => {
  const code = await readFile('src-tauri/src/settings.rs', 'utf8');
  for (const nativeTest of [
    'load_and_save_refuse_symlinked_settings_directory_without_touching_target',
    'settings_reject_group_writable_parent_before_read_or_write',
    'pinned_parent_descriptor_keeps_atomic_write_out_of_swapped_symlink',
    'settings_loader_rejects_symlinks_hardlinks_and_public_file_mode',
    'settings_loader_rejects_fifo_without_blocking',
    'bounded_settings_load_and_save_reject_oversize_without_replacing_file',
    'malformed_or_unknown_json_fails_closed',
  ]) assert.ok(code.includes('fn ' + nativeTest + '('), nativeTest);
});
