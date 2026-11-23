import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync('src-tauri/src/tools/commands.rs', 'utf8');
const state = readFileSync('src-tauri/src/agent/mod.rs', 'utf8');
const registry = readFileSync('src-tauri/src/tools/registry.rs', 'utf8');
const native = source.slice(
  source.indexOf('async fn commit_serialized_roots_with_timeout'),
  source.indexOf('// Staged policy publication'),
);

test('all authorized native root commands acquire one mutation gate before blocking validation (#156)', () => {
  assert.match(state, /root_mutations:\s*Arc<Mutex<RootGrantRevision>>/);
  assert.match(state, /root_mutations:\s*Arc::new\(Mutex::new\(RootGrantRevision::new\(\)\)\)/);
  const locked = native.indexOf('Arc::clone(&state.root_mutations).lock_owned().await');
  const validator = native.indexOf('tokio::task::spawn_blocking(move || {');
  const fairWriter = native.indexOf('state.registry.reserve_root_publication()', validator);
  const accepted = native.indexOf('tokio::task::spawn_blocking(move || {', fairWriter);
  const writerPermit = native.indexOf('let _root_write_admission = root_write_admission;', accepted);
  const settings = native.indexOf('state.settings.blocking_lock()', accepted);
  const published = native.indexOf('persist_root_grants(', accepted);
  const advanced = native.indexOf('revision.advance()', published);
  assert.ok(locked > 0 && validator > locked && fairWriter > validator &&
    accepted > fairWriter && writerPermit > accepted && settings > writerPermit &&
    published > settings && advanced > published,
    'native arrival-order gate must enter cancellable validation, then owned accepted commit on blocking worker');
  assert.match(native, /tokio::task::spawn_blocking\(move \|\| \{[\s\S]*?let _validation_permit = validation_permit;\s*validate\(roots\)/);
  assert.match(native, /\.map_err\(\|_\| "Cannot validate approved roots"\.to_owned\(\)\)\?\?/);
});

test('trusted sender origin is validated before native grants can acquire the gate (#156)', () => {
  const cmd = native.slice(native.indexOf('pub async fn set_allowed_roots('));
  assert.match(cmd, /navigation::ensure_privileged_webview\(&window\)\?;/);
  assert.match(cmd, /commit_serialized_roots\(\s*&\*state,\s*roots,/);
  assert.match(cmd, /\|requested\| ToolRegistry::canonical_roots\(&requested\)/);
  assert.match(cmd, /AgentSettings::save/);
  assert.doesNotMatch(cmd, /let resolved = ToolRegistry::canonical_roots\(&roots\)/);
});

test('native async fixture proves first validated write cannot be overtaken by later revocation (#156)', () => {
  assert.match(source, /async fn native_root_calls_commit_in_validation_entry_order_even_if_first_is_slow\(\)/);
  assert.match(source, /async fn invalid_validation_releases_native_mutation_guard_without_publication\(\)/);
  assert.match(source, /async fn cancelled_native_validation_worker_cannot_publish_a_stale_grant\(\)/);
  assert.match(source, /async fn accepted_commit_survives_canceled_caller_without_blocking_tokio\(\)/);
  assert.match(source, /tokio::test\(flavor = "current_thread"\)/);
  assert.match(source, /let \(started_tx, started_rx\) = tokio::sync::oneshot::channel\(\)/);
  assert.match(source, /let \(continue_tx, continue_rx\) = std::sync::mpsc::channel\(\)/);
  assert.match(source, /let \(second_queued_tx, second_queued_rx\) = tokio::sync::oneshot::channel\(\)/);
  assert.match(source, /second_queued_rx.await.unwrap\(\)/);
  assert.match(source, /tokio::time::timeout\(Duration::from_millis\(75\), &mut second_started_rx\)/);
  assert.match(source, /assert!\(state\.settings\.lock\(\)\.await\.allowed_roots\.is_empty\(\)\)/);
});

test('accepted root commit is moved off the Tokio executor, retaining the CAS guard across cancellation (#173)', () => {
  assert.match(native, /Arc::clone\(&state\.root_mutations\)\.lock_owned\(\)\.await/);
  assert.match(native, /tokio::task::spawn_blocking\(move \|\| \{\s*let _root_write_admission = root_write_admission;\s*let mut settings = state\.settings\.blocking_lock\(\)/);
  assert.match(native, /persist_root_grants\(&mut settings, &state\.registry, resolved, persist\)\?/);
  assert.match(native, /revision\.advance\(\);\s*Ok::<\(\), String>\(\(\)\)/);
  assert.doesNotMatch(native, /let mut settings = state\.settings\.lock\(\)\.await/);
  assert.match(source, /let mut readback = tokio::spawn\(async move \{/);
  assert.match(source, /readback must await the accepted commit/);
});

test('fair root writer intent queues after validated CAS before accepted blocking publication (#177)', () => {
  assert.match(native, /let root_write_admission = tokio::time::timeout\([\s\S]*?state\.registry\.reserve_root_publication\(\),[\s\S]*?\)\s*\.await/);
  assert.match(native, /let _root_write_admission = root_write_admission/);
  assert.match(registry, /async fn queued_root_writer_precedes_later_admitted_file_read\(\)/);
  assert.match(registry, /async fn scoped_read_slots_bound_active_and_waiting_workers\(\)/);
});
