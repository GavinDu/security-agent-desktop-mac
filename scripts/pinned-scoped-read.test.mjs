import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('scoped file uses pinned directory-FD openat traversal, leaf caps and races (#94 #115)', async () => {
  const source = await readFile('src-tauri/src/tools/pinned_read.rs', 'utf8');
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const commands = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  assert.match(source, /struct GrantedRoot/);
  assert.match(source, /fn pin_absolute_directory\(path: &Path\)/);
  assert.match(source, /libc::openat\(/);
  assert.match(source, /libc::O_RDONLY \| libc::O_NOFOLLOW \| libc::O_CLOEXEC/);
  assert.match(source, /Component::Normal\(name\)/);
  assert.match(source, /let Component::Normal\(name\) = component/);
  assert.match(source, /file\.take\(MAX_FILE_BYTES \+ 1\)/);
  assert.match(source, /metadata\.nlink\(\) != 1/);
  assert.match(registry, /self\.scoped_read_grant\(&path\)/);
  assert.match(registry, /spawn_blocking\(move \|\| \{/);
  assert.match(registry, /fn parent_symlink_swap_during_approval_is_denied/);
  assert.match(source, /fn pinned_root_is_not_replaced_by_renaming_the_granted_path/);
  assert.match(source, /fn preserves_leaf_type_nlink_utf8_and_64k_limit/);
  assert.match(commands, /grant\.path\(\)\.to_string_lossy\(\)/);
  assert.doesNotMatch(registry, /tokio::fs::read\(&path\)/);
});
