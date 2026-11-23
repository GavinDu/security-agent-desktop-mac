import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('unaccepted native Clear/Grant admission times out without accepting a writer (#185)', async () => {
  const source = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const doc = await readFile('docs/ROOT_WRITER_ADMISSION_TIMEOUT.md', 'utf8');
  assert.match(source, /const ROOT_PUBLICATION_ADMISSION_TIMEOUT: Duration = Duration::from_secs\(10\);/);
  assert.match(source, /commit_serialized_roots_with_timeout\([\s\S]*?ROOT_PUBLICATION_ADMISSION_TIMEOUT,/);
  const body = source.slice(source.indexOf('async fn commit_serialized_roots_with_timeout<'));
  const reserve = body.indexOf('state.registry.reserve_root_publication()');
  const deadline = body.lastIndexOf('tokio::time::timeout(', reserve);
  const accepted = body.indexOf('// COMMIT ACCEPTANCE:');
  const worker = body.indexOf('tokio::task::spawn_blocking(move || {', accepted);
  assert.ok(deadline >= 0 && reserve > deadline && accepted > reserve && worker > accepted,
    'timeout applies before the accepted non-cancellable blocking commit');
  assert.match(body.slice(deadline, accepted),
    /Directory permission change not committed; retry after active reads finish/);
  assert.doesNotMatch(body.slice(accepted, worker), /timeout\(/);
  assert.match(source, /async fn unaccepted_root_writer_times_out_without_publishing_and_retry_recovers\(\)/);
  assert.match(source, /assert_eq!\(persist_count\.load\(Ordering::SeqCst\), 0\);/);
  assert.match(source, /assert_eq!\(persist_count\.load\(Ordering::SeqCst\), 1\);/);
  assert.match(doc, /previous grant remains effective/);
});
