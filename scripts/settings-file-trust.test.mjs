import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('persisted root grants require a bounded no-follow settings file descriptor (#87)', async () => {
  const settings = await readFile('src-tauri/src/settings.rs', 'utf8');
  const limit = settings.indexOf('const MAX_SETTINGS_BYTES: u64 = 256 * 1024');
  const nofollow = settings.indexOf('opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)');
  const open = settings.indexOf('let mut file = match opts.open(path)');
  assert.ok(limit > 0 && nofollow > limit && open > nofollow);
  assert.match(settings, /metadata\.nlink\(\)\s*!=\s*1/);
  assert.match(settings, /metadata\.permissions\(\)\.mode\(\)\s*&\s*0o777\s*!=\s*0o600/);
  assert.match(settings, /file\.take\(MAX_SETTINGS_BYTES \+ 1\)/);
  assert.match(settings, /bytes\.len\(\) as u64 > MAX_SETTINGS_BYTES/);
  assert.match(settings, /fn settings_loader_rejects_symlinks_hardlinks_and_public_file_mode/);
  assert.match(settings, /fn bounded_settings_load_and_save_reject_oversize_without_replacing_file/);
  assert.doesNotMatch(settings, /fs::read\(path\)/);
});

test('settings loading must reject a swapped-in FIFO without a blocking open (#106)', async () => {
  const source = await readFile('src-tauri/src/settings.rs', 'utf8');
  assert.match(source, /opts\.custom_flags\(libc::O_NOFOLLOW \| libc::O_CLOEXEC \| libc::O_NONBLOCK\)/);
  assert.match(source, /fn settings_loader_rejects_fifo_without_blocking/);
  assert.match(source, /libc::mkfifo\(c_path\.as_ptr\(\), 0o600\)/);
  assert.match(source, /Unsafe or oversized settings\.json/);
});
