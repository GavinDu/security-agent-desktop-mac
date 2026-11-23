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
  assert.match(registry, /Self::scoped_read_with_lease\(&roots, &read_path,/);
  assert.match(registry, /let grants = roots\.read\(\)\.expect\("roots lock poisoned"\)/);
  assert.match(registry, /spawn_blocking\(move \|\| \{/);
  assert.match(registry, /fn parent_symlink_swap_during_approval_is_denied/);
  assert.match(source, /fn pinned_root_is_not_replaced_by_renaming_the_granted_path/);
  assert.match(source, /fn preserves_leaf_type_nlink_utf8_and_64k_limit/);
  assert.match(commands, /grant\.path\(\)\.to_string_lossy\(\)/);
  assert.doesNotMatch(registry, /tokio::fs::read\(&path\)/);
});

test('revocation acknowledgment waits for complete FD-relative file read (#164)', async () => {
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const lease = registry.slice(registry.indexOf('fn scoped_read_with_lease'),
    registry.indexOf('fn allowed_path('));
  const invoke = registry.slice(registry.indexOf('pub async fn invoke('),
    registry.indexOf('#[derive(Deserialize)]'));
  assert.match(registry, /roots: Arc<RwLock<Vec<crate::tools::pinned_read::GrantedRoot>>>/);
  assert.match(lease, /let grants = roots\.read\(\)/);
  assert.match(lease, /grant\.clone_directory\(\)\?/);
  assert.match(lease, /return read\(&pinned, relative\)/);
  assert.doesNotMatch(lease, /drop\(grants\)/);
  assert.match(invoke, /tokio::task::spawn_blocking\(move \|\| \{[\s\S]*?Self::scoped_read_with_lease\(&roots, &read_path,/);
  assert.match(invoke, /crate::tools::pinned_read::read_scoped_file\(fd, relative\)/);
  assert.doesNotMatch(invoke, /tokio::fs::read\(|self\.scoped_read_grant\(&path\)/);
  assert.match(registry, /fn acknowledged_root_revoke_waits_for_inflight_scoped_file_read/);
  assert.match(registry, /fn revoked_root_precedes_any_queued_scoped_read/);
  assert.match(registry, /writer_registry\.set_roots\(Vec::new\(\)\)/);
  assert.match(registry, /revoked_rx\.recv_timeout\(Duration::from_millis\(80\)\)/);
  assert.match(registry, /assert_eq!\(denied, "Path outside granted roots"\)/);
});
