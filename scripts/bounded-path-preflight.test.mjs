import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('pre/post-approval filesystem metadata checks run in bounded blocking worker (#183)', async () => {
  const src = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(src, /const MAX_ADMITTED_PATH_PREFLIGHTS: usize = 16/);
  assert.match(src, /path_preflight_slots: Arc<Semaphore>/);
  assert.match(src, /path_preflight_slots: Arc::new\(Semaphore::new\(MAX_ADMITTED_PATH_PREFLIGHTS\)\)/);
  assert.match(src, /async fn offload_path_check\(/);
  assert.match(src, /\.try_acquire_owned\(\)/);
  assert.match(src, /tokio::task::spawn_blocking\(move \|\| \{\s*let _slot = slot;/);
  assert.match(src, /async fn allowed_path_for_tool\(/);
  assert.match(src, /let resolved = Self::allowed_path_against\(&roots, &root_admission, &requested\)\?/);
  assert.match(src, /if require_directory && !resolved\.is_dir\(\)/);
  assert.match(src, /async fn reauthorize_after_approval\(/);
  assert.match(src, /\.allowed_path_for_tool\(approved\.to_path_buf\(\), tool == "bash__run"\)/);
  assert.match(src, /async fn blocking_path_preflight_stays_bounded_after_request_cancellation\(/);
  assert.match(src, /async fn async_path_preflight_preserves_grants_and_directory_type\(/);

  const invocation = src.slice(src.indexOf('pub async fn invoke('), src.indexOf('#[derive(Deserialize)]', src.indexOf('pub async fn invoke(')));
  assert.match(invocation, /allowed_path_for_tool\(PathBuf::from\(&input\.path\), false\)\.await/);
  assert.match(invocation, /allowed_path_for_tool\(PathBuf::from\(&input\.cwd\), true\)/);
  assert.match(invocation, /reauthorize_after_approval\("filesystem__read_file", &path\)\s*\.await/);
  assert.match(invocation, /reauthorize_after_approval\("bash__run", &directory\)\s*\.await/);
  assert.doesNotMatch(invocation, /\.canonicalize\(\)|\.is_dir\(\)|self\.allowed_path\(/);
});
