import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('root validation slots stay with blocking workers and Clear bypasses saturated Grant slots (#187)', async () => {
  const source = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const state = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  const docs = await readFile('docs/ROOT_VALIDATION_BUDGET.md', 'utf8');
  assert.match(state, /const MAX_ROOT_VALIDATION_WORKERS: usize = 4/);
  assert.match(state, /root_validation_slots: Arc<Semaphore>/);
  assert.match(state, /root_validation_slots: Arc::new\(Semaphore::new\(MAX_ROOT_VALIDATION_WORKERS\)\)/);
  assert.match(source, /const ROOT_VALIDATION_TIMEOUT: Duration = Duration::from_secs\(10\);/);

  const mutation = source.slice(source.indexOf('async fn commit_serialized_roots_with_timeout<'),
    source.indexOf('#[tauri::command]', source.indexOf('async fn commit_serialized_roots_with_timeout<')));
  const revision = mutation.indexOf('Arc::clone(&state.root_mutations).lock_owned().await');
  const bypass = mutation.indexOf('if roots.is_empty()');
  const slot = mutation.indexOf('try_acquire_owned()', bypass);
  const bounded = mutation.indexOf('tokio::time::timeout(', slot);
  const spawned = mutation.indexOf('tokio::task::spawn_blocking(move || {', bounded);
  const owned = mutation.indexOf('let _validation_permit = validation_permit;', spawned);
  const validate = mutation.indexOf('validate(roots)', owned);
  const writer = mutation.indexOf('state.registry.reserve_root_publication()', validate);
  const accepted = mutation.indexOf('// COMMIT ACCEPTANCE:', writer);
  assert.ok(revision >= 0 && bypass > revision && slot > bypass &&
    bounded > slot && spawned > bounded && owned > spawned &&
    validate > owned && writer > validate && accepted > writer,
    'must time-bound caller validation before accepting the fair writer and keep slot in blocking worker');
  assert.match(mutation, /Directory permission validation not committed; retry/);
  assert.match(mutation, /Directory validation capacity exceeded/);
  assert.match(mutation, /Cannot validate approved roots/);
  assert.match(source, /async fn stalled_native_grant_validation_times_out_but_clear_remains_authoritative\(\)/);
  assert.match(source, /async fn abandoned_nonempty_root_validators_keep_worker_slots_until_exit\(\)/);
  assert.match(docs, /Empty Clear is exempt from the Grant validation capacity limit/);
  assert.match(docs, /does not interrupt a frozen NFS syscall/);
});
