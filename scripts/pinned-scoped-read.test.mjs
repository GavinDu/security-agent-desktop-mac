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
  assert.match(registry, /let grants = roots\s*\.read\(\)\s*\.map_err\(\|_\| "Directory permission registry unavailable"/);
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
  assert.match(lease, /let grants = roots\s*\.read\(\)/);
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

test('fair writer priority, bounded admitted FD reads and owned cancellation guards (#177)', async () => {
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const commands = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  assert.match(registry, /root_admission: Arc<AsyncRwLock<\(\)>>/);
  assert.match(registry, /read_slots: Arc<Semaphore>/);
  assert.match(registry, /const MAX_ADMITTED_FILE_READS: usize = 32/);
  assert.match(registry, /\.try_acquire_owned\(\)/);
  assert.match(registry, /Arc::clone\(&self\.root_admission\)\.read_owned\(\)\.await/);
  assert.match(registry, /Arc::clone\(&self\.root_admission\)\.write_owned\(\)\.await/);
  const invoke = registry.slice(registry.indexOf('pub async fn invoke('),
    registry.indexOf('#[derive(Deserialize)]'));
  const admitted = invoke.indexOf('let (read_slot, read_gate) = self.admit_scoped_read().await?');
  const spawned = invoke.indexOf('tokio::task::spawn_blocking(move || {');
  const heldSlot = invoke.indexOf('let _read_slot = read_slot;', spawned);
  const heldGate = invoke.indexOf('let _read_gate = read_gate;', spawned);
  const fdRead = invoke.indexOf('Self::scoped_read_with_lease', spawned);
  assert.ok(admitted > 0 && spawned > admitted && heldSlot > spawned &&
    heldGate > heldSlot && fdRead > heldGate,
    'owned permits must be moved into the blocking FD worker, not dropped with HTTP caller');
  assert.match(registry, /root_admission\s*\.try_read\(\)\s*\.map_err\(\|_\| "Directory permission update pending"/);
  assert.match(registry, /fn queued_root_writer_precedes_later_admitted_file_read/);
  assert.match(registry, /fn scoped_read_slots_bound_active_and_waiting_workers/);
  const mutation = commands.slice(commands.indexOf('async fn commit_serialized_roots'),
    commands.indexOf('#[tauri::command]', commands.indexOf('async fn commit_serialized_roots')));
  assert.match(mutation, /reserve_root_publication\(\)\.await/);
  assert.match(mutation, /let _root_write_admission = root_write_admission/);
  assert.doesNotMatch(mutation, /blocking_write\(\)/);
});

test('post-worker file result generation recheck rejects completed reads invalidated by Clear (#179)', async () => {
  const source = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(source, /root_generation: AtomicU64/);
  assert.match(source, /root_generation: AtomicU64::new\(0\)/);
  const publish = source.slice(source.indexOf('pub(crate) fn commit_roots_transaction('),
    source.indexOf('fn set_roots(', source.indexOf('pub(crate) fn commit_roots_transaction(')));
  const persist = publish.indexOf('persist()?');
  const update = publish.indexOf('*current = roots');
  const epoch = publish.indexOf('root_generation.fetch_add(1, Ordering::AcqRel)');
  assert.ok(persist > 0 && update > persist && epoch > update);
  assert.match(publish, /u64::MAX/);
  const file = source.slice(source.indexOf('"filesystem__read_file" => {'),
    source.indexOf('"bash__run" => {'));
  const admitted = file.indexOf('let (read_slot, read_gate) = self.admit_scoped_read().await?');
  const capture = file.indexOf('let read_generation = self.root_generation.load(Ordering::Acquire)');
  const spawned = file.indexOf('tokio::task::spawn_blocking(move || {');
  const readReturned = file.indexOf('.map_err(|_| "Approved file read task failed")??;');
  const validated = file.indexOf('self.ensure_current_file_result(read_generation)?;');
  const json = file.indexOf('Ok(json!({ "path": path, "content": text }))');
  assert.ok(admitted >= 0 && capture > admitted && spawned > capture &&
    readReturned > spawned && validated > readReturned && json > validated,
    'post-read epoch must be checked before successful content JSON is built');
  assert.match(source, /"File read authorization changed"/);
  assert.match(source, /fn completed_file_result_denied_after_root_clear_before_json_return/);
  assert.match(source, /fn root_generation_only_advances_after_successful_publication/);
  const command = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const http = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  assert.match(command, /state\.registry\.invoke\(call\)\.await/);
  assert.match(http, /state\.registry\.invoke\(call\)\.await/);
});
