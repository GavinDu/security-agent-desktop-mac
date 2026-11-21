import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync('src-tauri/src/tools/commands.rs', 'utf8');
const state = readFileSync('src-tauri/src/agent/mod.rs', 'utf8');
const native = source.slice(
  source.indexOf('async fn commit_serialized_roots'),
  source.indexOf('// Staged policy publication'),
);

test('all authorized native root commands acquire one mutation gate before blocking validation (#156)', () => {
  assert.match(state, /root_mutations:\s*Mutex<\(\)>/);
  assert.match(state, /root_mutations:\s*Mutex::new\(\(\)\)/);
  const locked = native.indexOf('state.root_mutations.lock().await');
  const blocked = native.indexOf('tokio::task::spawn_blocking(');
  const settings = native.indexOf('state.settings.lock().await');
  const published = native.indexOf('persist_root_grants(');
  assert.ok(locked > 0 && blocked > locked && settings > blocked && published > settings,
    'mutations must be serialized through validation, staged save and publication');
  assert.match(native, /move \|\| validate\(roots\)/);
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
  assert.match(source, /let \(started_tx, started_rx\) = tokio::sync::oneshot::channel\(\)/);
  assert.match(source, /let \(continue_tx, continue_rx\) = std::sync::mpsc::channel\(\)/);
  assert.match(source, /let \(second_queued_tx, second_queued_rx\) = tokio::sync::oneshot::channel\(\)/);
  assert.match(source, /second_queued_rx.await.unwrap\(\)/);
  assert.match(source, /tokio::time::timeout\(Duration::from_millis\(75\), &mut second_started_rx\)/);
  assert.match(source, /assert!\(state\.settings\.lock\(\)\.await\.allowed_roots\.is_empty\(\)\)/);
});
